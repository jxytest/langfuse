import { ApiAuthService } from "@/src/features/public-api/server/apiAuth";
import { cors, runMiddleware } from "@/src/features/public-api/server/cors";
import { prisma } from "@langfuse/shared/src/db";
import { isPrismaException } from "@/src/utils/exceptions";
import { type NextApiRequest, type NextApiResponse } from "next";
import { z } from "zod/v4";
import {
  UnauthorizedError,
  BaseError,
  MethodNotAllowedError,
  ForbiddenError,
  GetPromptVersionsSchema,
  PRODUCTION_LABEL,
} from "@langfuse/shared";
import {
  PromptService,
  redis,
  recordIncrement,
  traceException,
  logger,
} from "@langfuse/shared/src/server";
import { RateLimitService } from "@/src/features/public-api/server/RateLimitService";
import { telemetry } from "@/src/features/telemetry";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  await runMiddleware(req, res, cors);

  try {
    // Authentication and authorization
    const authCheck = await new ApiAuthService(
      prisma,
      redis,
    ).verifyAuthHeaderAndReturnScope(req.headers.authorization);

    if (!authCheck.validKey) throw new UnauthorizedError(authCheck.error);
    if (
      authCheck.scope.accessLevel !== "project" ||
      !authCheck.scope.projectId
    ) {
      throw new ForbiddenError(
        `Access denied: Bearer auth and org api keys are not allowed to access`,
      );
    }

    await telemetry();

    // Only handle GET requests
    if (req.method === "GET") {
      const searchParams = GetPromptVersionsSchema.parse(req.query);
      const projectId = authCheck.scope.projectId;
      const promptName = searchParams.name;

      const rateLimitCheck =
        await RateLimitService.getInstance().rateLimitRequest(
          authCheck.scope,
          "prompts",
        );

      if (rateLimitCheck?.isRateLimited()) {
        return rateLimitCheck.sendRestResponseIfLimited(res);
      }

      // Get all versions of the prompt
      const prompts = await prisma.prompt.findMany({
        where: {
          projectId,
          name: promptName,
        },
        orderBy: [
          { version: "desc" }, // Latest versions first
          { createdAt: "desc" },
        ],
      });

      if (prompts.length === 0) {
        return res.status(404).json({
          error: "NotFoundError",
          message: "No versions found for the specified prompt name",
        });
      }

      const promptService = new PromptService(prisma, redis, recordIncrement);

      // Resolve all prompts (handle dependencies if any)
      const resolvedPrompts = await Promise.all(
        prompts.map(async (prompt) => {
          const resolvedPrompt = await promptService.resolvePrompt(prompt);
          return {
            ...resolvedPrompt,
            isActive: resolvedPrompt?.labels.includes(PRODUCTION_LABEL) ?? false,
          };
        }),
      );

      return res.status(200).json({
        data: resolvedPrompts,
        meta: {
          totalVersions: prompts.length,
          promptName: promptName,
        },
      });
    }

    throw new MethodNotAllowedError();
  } catch (error: unknown) {
    logger.error(error);
    traceException(error);

    if (error instanceof BaseError) {
      return res.status(error.httpCode).json({
        error: error.name,
        message: error.message,
      });
    }

    if (isPrismaException(error)) {
      return res.status(500).json({
        error: "Internal Server Error",
        message: "An unknown database error occurred",
      });
    }

    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: "ValidationError",
        message: "Invalid request data",
        details: error.issues,
      });
    }

    return res.status(500).json({
      error: "InternalServerError",
      message:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
}
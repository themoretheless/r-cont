import type { NextConfig } from "next";

const repositoryName = process.env.GITHUB_REPOSITORY?.split("/")[1] ?? "";
const isRootPagesRepository = repositoryName.endsWith(".github.io");
const isPagesBuild = process.env.BUILD_TARGET === "pages";
const pagesBasePath = isPagesBuild && process.env.GITHUB_ACTIONS && repositoryName && !isRootPagesRepository
  ? `/${repositoryName}`
  : "";

const nextConfig: NextConfig = {
  ...(isPagesBuild
    ? {
        output: "export" as const,
        trailingSlash: true,
        basePath: pagesBasePath,
        assetPrefix: pagesBasePath,
      }
    : {}),
  images: { unoptimized: true },
  // The shared vinext starter also contains Cloudflare-only worker modules.
  // The GitHub Pages surface is checked separately by typecheck:pages.
  typescript: { ignoreBuildErrors: true },
};

export default nextConfig;

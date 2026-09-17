import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  cacheComponents: true,
  experimental: {
    useTypeScriptCli: false,
  },
};

export default nextConfig;

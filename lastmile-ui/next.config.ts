import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  webpack(config) {
    config.module.rules.push({
      test: /\.txt$/,
      type: "asset/source",
    });
    return config;
  },
};

export default nextConfig;

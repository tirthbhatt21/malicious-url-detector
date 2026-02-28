/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export", 
  images: {
    unoptimized: true,
  },
  trailingSlash: true,
  basePath: "/malicious-url-detector",
  assetPrefix: "/malicious-url-detector/",
};

module.exports = nextConfig;
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export", // REQUIRED for GitHub Pages
  images: {
    unoptimized: true, // GitHub Pages does not support next/image optimization
  },
  trailingSlash: true, // Prevents 404s on refresh
};

module.exports = nextConfig;
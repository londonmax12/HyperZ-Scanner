FROM node:20-alpine

# vuln-nextjs: a real, unpatched Next.js install (14.2.24, one minor
# below the 14.2.25 CVE-2025-29927 patch) so the
# nextjs-middleware-bypass integration test exercises the live
# x-middleware-subrequest depth-saturation trick against the actual
# runtime, not a hand-crafted oracle. The middleware.js gates
# /dashboard with a NextResponse.redirect; the CVE causes Next's
# runtime to skip the middleware entirely when the attacker-supplied
# header saturates the subrequest depth counter, landing the request
# on the unprotected page handler with a 200.
#
# `next build` runs at image-build time so the image cache absorbs the
# compile cost; `next start` is what runs in the container and is
# sub-second on a warm image.

WORKDIR /app

COPY package.json /app/
RUN npm install --omit=dev

COPY next.config.js middleware.js /app/
COPY pages /app/pages

RUN npx next build

EXPOSE 8085
CMD ["npx", "next", "start", "-p", "8085", "-H", "0.0.0.0"]

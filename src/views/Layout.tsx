import type { Child } from "hono/jsx";

export function Layout({ title, header, children }: { title: string; header?: Child; children: Child }) {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title}</title>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;600;700&family=Barlow+Condensed:wght@500;600;700&display=swap"
        />
        <link rel="stylesheet" href="/style.css" />
        <script src="/app.js" defer></script>
      </head>
      <body>
        {header}
        <main>{children}</main>
      </body>
    </html>
  );
}

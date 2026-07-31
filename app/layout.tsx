import type { Metadata } from "next";
import "./globals.css";

const repositoryName = process.env.GITHUB_REPOSITORY?.split("/")[1] ?? "";
const repositoryOwner = process.env.GITHUB_REPOSITORY_OWNER ?? "";
const isRootPagesRepository = repositoryName.endsWith(".github.io");
const pagesPath = repositoryName && !isRootPagesRepository ? `/${repositoryName}/` : "/";
const publicOrigin = repositoryOwner
  ? `https://${repositoryOwner}.github.io${pagesPath}`
  : "http://localhost:3000/";

export const metadata: Metadata = {
  metadataBase: new URL(publicOrigin),
  title: "DirectLink — P2P через NAT в браузере",
  description: "Соедините две машины напрямую через WebRTC DataChannel с ручным обменом offer и answer.",
  openGraph: {
    title: "DirectLink — P2P через NAT в браузере",
    description: "Две машины, два кода и прямой зашифрованный WebRTC DataChannel без backend-сервера.",
    type: "website",
    images: [{ url: "og.png", width: 1200, height: 630, alt: "DirectLink соединяет две машины через NAT" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "DirectLink — P2P через NAT в браузере",
    description: "Ручной offer/answer и прямой WebRTC DataChannel.",
    images: ["og.png"],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}

import { Layout } from "antd";
import React from "react";

interface FooterProps {
    version: string;
}

export const Footer: React.FC<FooterProps> = ({ version }) => (
    <Layout.Footer className="text-center">
        <p className="m-0">Auth Server Version: {version}</p>
    </Layout.Footer>
);

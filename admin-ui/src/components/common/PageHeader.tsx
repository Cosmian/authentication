import { Button, Typography } from "antd";
import React from "react";

const { Title, Text } = Typography;

interface PageHeaderProps {
    title: string;
    description?: string;
    actionLabel?: string;
    onAction?: () => void;
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, actionLabel, onAction }) => (
    <div className="flex items-center justify-between mb-4">
        <div>
            <Title level={2} className="m-0">
                {title}
            </Title>
            {description && <Text type="secondary">{description}</Text>}
        </div>
        {actionLabel && onAction && (
            <Button type="primary" onClick={onAction}>
                {actionLabel}
            </Button>
        )}
    </div>
);

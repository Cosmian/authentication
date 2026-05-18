import { Button, Empty } from "antd";
import React from "react";

interface EmptyStateProps {
    description?: string;
    actionLabel?: string;
    onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ description = "No data", actionLabel, onAction }) => (
    <div className="flex items-center justify-center py-16">
        <Empty description={description}>
            {actionLabel && onAction && (
                <Button type="primary" onClick={onAction}>
                    {actionLabel}
                </Button>
            )}
        </Empty>
    </div>
);

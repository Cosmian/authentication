import { Spin } from "antd";
import React from "react";

interface LoadingStateProps {
    message?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({ message = "Loading..." }) => (
    <div className="flex items-center justify-center py-16">
        <Spin size="large" tip={message}>
            <div className="p-12" />
        </Spin>
    </div>
);

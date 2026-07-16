import { Alert, Modal, Typography } from "antd";
import React from "react";
import type { AppRoleSecretIdResult } from "../../types/api";

interface SecretIdResultModalProps {
    open: boolean;
    roleName: string;
    roleId: string;
    result: AppRoleSecretIdResult | null;
    onClose: () => void;
}

/** Displays a freshly generated SecretID. The `secret_id` is shown only once. */
export const SecretIdResultModal: React.FC<SecretIdResultModalProps> = ({ open, roleName, roleId, result, onClose }) => (
    <Modal
        title={`SecretID generated — ${roleName}`}
        open={open}
        onCancel={onClose}
        onOk={onClose}
        okText="Done"
        cancelButtonProps={{ style: { display: "none" } }}
        destroyOnHidden
    >
        <Alert
            type="warning"
            showIcon
            className="mb-4"
            message="Copy the SecretID now"
            description="This SecretID is shown only once and cannot be retrieved later. The RoleID and SecretID together form the AppRole login credentials."
        />
        <Typography.Paragraph className="m-0">
            <Typography.Text strong>RoleID</Typography.Text>
            <br />
            <Typography.Text copyable code>
                {roleId}
            </Typography.Text>
        </Typography.Paragraph>
        <Typography.Paragraph className="m-0 mt-3">
            <Typography.Text strong>SecretID</Typography.Text>
            <br />
            <Typography.Text copyable code>
                {result?.secret_id ?? ""}
            </Typography.Text>
        </Typography.Paragraph>
        <Typography.Paragraph className="m-0 mt-3">
            <Typography.Text strong>SecretID accessor</Typography.Text>
            <br />
            <Typography.Text copyable code>
                {result?.secret_id_accessor ?? ""}
            </Typography.Text>
        </Typography.Paragraph>
    </Modal>
);

import { Alert, Modal, Space, Typography } from "antd";
import React from "react";

const { Text, Paragraph } = Typography;

interface OidcClientSecretModalProps {
    open: boolean;
    clientId: string;
    clientSecret: string;
    /** Issuer URL of the auth-verifier (used in the KMS config snippet). */
    issuerUrl: string;
    onClose: () => void;
}

/**
 * Shows the client_secret exactly once after a client has been created.
 *
 * The secret is **never** returned by the server again — the user must copy it now.
 */
const OidcClientSecretModal: React.FC<OidcClientSecretModalProps> = ({ open, clientId, clientSecret, issuerUrl, onClose }) => (
    <Modal
        open={open}
        title="Client registered — save your secret"
        onOk={onClose}
        onCancel={onClose}
        cancelButtonProps={{ style: { display: "none" } }}
        okText="I have copied the secret"
        data-testid="oidc-client-secret-modal"
        width={560}
    >
        <Alert
            type="warning"
            showIcon
            className="mb-4"
            message="The client secret is shown only once. Copy it now — it cannot be retrieved later."
        />

        <Space direction="vertical" size={8} className="w-full">
            <div>
                <Text type="secondary" className="text-xs block mb-1">
                    Client ID
                </Text>
                <Paragraph code copyable className="mb-0" data-testid="oidc-new-client-id">
                    {clientId}
                </Paragraph>
            </div>
            <div>
                <Text type="secondary" className="text-xs block mb-1">
                    Client Secret
                </Text>
                <Paragraph code copyable className="mb-0" data-testid="oidc-new-client-secret">
                    {clientSecret}
                </Paragraph>
            </div>
        </Space>

        <Alert
            type="info"
            showIcon
            className="mt-4"
            message="Add these values to your KMS config:"
            description={
                <pre className="text-xs mt-2 whitespace-pre-wrap">
                    {`[ui_config.ui_oidc_auth]\nui_oidc_issuer_url    = "${issuerUrl}"\nui_oidc_client_id     = "${clientId}"\nui_oidc_client_secret = "${clientSecret}"`}
                </pre>
            }
        />
    </Modal>
);

export default OidcClientSecretModal;

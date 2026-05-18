import { Alert, Button, Input, Modal, Space, Typography } from "antd";
import React, { useState } from "react";
import type { TotpGenerateResponse } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createTotpApi } from "../../services/totpApi";

interface TotpManagementModalProps {
    open: boolean;
    adminId: string;
    realmId: string;
    totpEnabled: boolean;
    onClose: () => void;
    onSuccess: () => void;
}

export const TotpManagementModal: React.FC<TotpManagementModalProps> = ({ open, adminId, realmId, totpEnabled, onClose, onSuccess }) => {
    const { serverUrl } = useAuth();
    const [step, setStep] = useState<"idle" | "generated" | "verifying">("idle");
    const [totpData, setTotpData] = useState<TotpGenerateResponse | null>(null);
    const [code, setCode] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const api = createTotpApi(serverUrl);

    const handleGenerate = async () => {
        setLoading(true);
        setError(null);
        try {
            const result = await api.generate(realmId, { username: adminId });
            setTotpData(result);
            setStep("generated");
        } catch {
            setError("Failed to generate TOTP secret");
        } finally {
            setLoading(false);
        }
    };

    const handleVerify = async () => {
        if (code.length !== 6) {
            setError("Please enter a 6-digit code");
            return;
        }
        if (!totpData) {
            setError("Missing TOTP secret — please regenerate");
            return;
        }
        setLoading(true);
        setError(null);
        try {
            await api.verify(realmId, {
                username: adminId,
                token: code,
                secret: totpData.secret_base32,
            });
            onSuccess();
            resetState();
        } catch {
            setError("Invalid TOTP code");
        } finally {
            setLoading(false);
        }
    };

    const handleDisable = async () => {
        setLoading(true);
        setError(null);
        try {
            await api.disable(realmId, adminId);
            onSuccess();
            resetState();
        } catch {
            setError("Failed to disable TOTP");
        } finally {
            setLoading(false);
        }
    };

    const resetState = () => {
        setStep("idle");
        setTotpData(null);
        setCode("");
        setError(null);
    };

    const handleClose = () => {
        resetState();
        onClose();
    };

    return (
        <Modal title={`TOTP for "${adminId}"`} open={open} onCancel={handleClose} footer={null} destroyOnClose>
            {error && <Alert type="error" message={error} showIcon className="mb-4" />}

            {totpEnabled ? (
                <div>
                    <Alert type="success" message="TOTP is currently enabled" showIcon className="mb-4" />
                    <Button danger onClick={handleDisable} loading={loading}>
                        Disable TOTP
                    </Button>
                </div>
            ) : step === "idle" ? (
                <div>
                    <Typography.Paragraph>
                        Generate a TOTP secret for this admin. They will need to scan the QR code with an authenticator app.
                    </Typography.Paragraph>
                    <Button type="primary" onClick={handleGenerate} loading={loading}>
                        Generate TOTP Secret
                    </Button>
                </div>
            ) : (
                <div>
                    <Alert type="info" message="Scan the QR code or enter the secret manually" className="mb-4" />
                    {totpData && (
                        <Space direction="vertical" className="w-full mb-4">
                            <div className="p-4 bg-white rounded text-center">
                                <img
                                    src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(totpData.otpauth_url)}`}
                                    alt="TOTP QR Code"
                                    width={200}
                                    height={200}
                                />
                            </div>
                            <Typography.Text copyable>{totpData.secret_base32}</Typography.Text>
                        </Space>
                    )}
                    <Space.Compact className="w-full">
                        <Input
                            placeholder="6-digit code"
                            value={code}
                            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                            maxLength={6}
                            onPressEnter={handleVerify}
                        />
                        <Button type="primary" onClick={handleVerify} loading={loading}>
                            Verify
                        </Button>
                    </Space.Compact>
                </div>
            )}
        </Modal>
    );
};

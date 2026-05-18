import { Input, Modal } from "antd";
import React, { useState } from "react";

export interface ConfirmDeleteModalProps {
    open: boolean;
    itemName: string;
    onConfirm: () => void;
    onCancel: () => void;
    loading?: boolean;
}

export const ConfirmDeleteModal: React.FC<ConfirmDeleteModalProps> = ({ open, itemName, onConfirm, onCancel, loading = false }) => {
    const [typed, setTyped] = useState("");

    const handleAfterClose = (): void => setTyped("");

    return (
        <Modal
            open={open}
            title={`Delete "${itemName}"?`}
            okText="Delete"
            okType="danger"
            okButtonProps={{ disabled: typed !== itemName, loading }}
            onOk={onConfirm}
            onCancel={onCancel}
            afterClose={handleAfterClose}
            destroyOnClose
        >
            <p>
                This action cannot be undone. Type <strong>{itemName}</strong> to confirm.
            </p>
            <Input placeholder={itemName} value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus />
        </Modal>
    );
};

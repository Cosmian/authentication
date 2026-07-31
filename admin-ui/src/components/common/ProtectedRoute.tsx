import React from "react";
import { Navigate, useLocation } from "react-router";
import { useAuth } from "../../contexts/AuthContext";
import { LoadingState } from "./LoadingState";

export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const { isAuthenticated, loading } = useAuth();
    const location = useLocation();

    if (loading) {
        return <LoadingState message="Checking session..." />;
    }

    if (!isAuthenticated) {
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    return <>{children}</>;
};

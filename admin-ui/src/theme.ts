import { theme } from "antd";

export const lightTheme = {
    components: {
        Layout: {
            headerBg: "#ffffff",
            footerPadding: "5px 50px",
        },
        Card: {
            colorBgContainer: "#ffffff",
            borderRadiusLG: 8,
        },
        Switch: {
            trackHeight: 32,
            handleSize: 28,
        },
        Button: {
            defaultHoverBorderColor: "#6e31e8",
            defaultHoverColor: "#6e31e8",
        },
    },
};

export const darkTheme = {
    algorithm: theme.darkAlgorithm,
    token: {
        colorTextPlaceholder: "#b9b9b9",
        colorError: "#e23030",
        colorBorder: "#4d4b4b",
        colorSplit: "#4d4b4b",
        colorBorderSecondary: "#4d4b4b",
        colorLink: "#9e6eff",
        colorLinkHover: "#c4a8ff",
    },
    components: {
        Layout: {
            headerBg: "#272d33",
            siderBg: "#272d33",
            triggerBg: "#272d33",
            footerPadding: "5px 50px",
        },
        Menu: {
            itemSelectedBg: "#393E46",
            itemSelectedColor: "#9e6eff",
            itemHoverBg: "#2e3238",
            itemActiveBg: "#393E46",
            itemActiveColor: "#9e6eff",
        },
        Button: {
            primaryShadow: "None",
            dangerShadow: "None",
            defaultBorderColor: "#e4dddd",
        },
        Select: {
            selectorBg: "#2f3239",
            colorBorder: "#34383f",
            optionActiveBg: "#9e6eff",
            optionActiveColor: "#2a2d30",
            optionSelectedBg: "#9e6eff",
            optionSelectedColor: "#2a2d30",
            colorIcon: "#9e6eff",
        },
        Input: {
            colorBorder: "#34383f",
        },
        Card: {
            colorBgContainer: "#393E46",
            borderRadiusLG: 8,
        },
        Switch: {
            trackHeight: 32,
            handleSize: 28,
        },
    },
};

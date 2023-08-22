import { AuthConfig } from "libs/angular-oauth2-oidc/projects/lib/src/public_api";

export const authCodeFlowConfig: AuthConfig = {
  issuer: "https://idsvr4.azurewebsites.net",
  redirectUri: window.location.origin + "/index.html",
  clientId: "spa",
  responseType: "code",
  scope: "openid profile email offline_access api",
  showDebugInformation: true,
  timeoutFactor: 0.01,
};

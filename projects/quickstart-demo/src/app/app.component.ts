import { Component } from "@angular/core";
import { OAuthService } from "libs/angular-oauth2-oidc/projects/lib/src/public_api";
import { filter } from "rxjs/operators";
import { authCodeFlowConfig } from "./auth.config";
import { JwksValidationHandler } from "libs/angular-oauth2-oidc/projects/angular-oauth2-oidc-jwks/src/public-api";

@Component({
  selector: "app-root",
  templateUrl: "./app.component.html",
  styleUrls: ["./app.component.css"],
})
export class AppComponent {
  title = "Quickstart Demo";

  constructor(private oauthService: OAuthService) {
    this.oauthService.configure(authCodeFlowConfig);
    this.oauthService.loadDiscoveryDocumentAndLogin();

    //this.oauthService.setupAutomaticSilentRefresh();

    // Automatically load user profile
    this.oauthService.events
      .pipe(filter((e) => e.type === "token_received"))
      .subscribe((_) => this.oauthService.loadUserProfile());
  }

  get userName(): string {
    const claims = this.oauthService.getIdentityClaims();
    if (!claims) return null;
    return claims["given_name"];
  }

  get idToken(): string {
    return this.oauthService.getIdToken();
  }

  get accessToken(): string {
    return this.oauthService.getAccessToken();
  }

  refresh() {
    this.oauthService.refreshToken();
  }
}

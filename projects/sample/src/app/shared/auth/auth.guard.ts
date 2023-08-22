import { Injectable } from "@angular/core";
import { CanActivate, Router } from "@angular/router";
import { OAuthService } from "libs/angular-oauth2-oidc/projects/lib/src/public_api";

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private router: Router, private oauthService: OAuthService) {}

  canActivate() {
    if (
      this.oauthService.hasValidAccessToken() &&
      this.oauthService.hasValidIdToken()
    ) {
      return true;
    } else {
      this.router.navigate(["/home", { login: true }]);
      return false;
    }
  }
}

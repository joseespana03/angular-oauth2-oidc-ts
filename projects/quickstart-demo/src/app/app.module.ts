import { BrowserModule } from "@angular/platform-browser";
import { NgModule } from "@angular/core";

import { AppComponent } from "./app.component";
import { OAuthModule, OAuthStorage } from "libs/angular-oauth2-oidc/projects/lib/src/public_api";
import { HttpClientModule } from "@angular/common/http";

@NgModule({
  imports: [BrowserModule, OAuthModule.forRoot(), HttpClientModule],
  declarations: [AppComponent],
  providers: [
    // { provide: OAuthStorage, useValue: localStorage }
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}

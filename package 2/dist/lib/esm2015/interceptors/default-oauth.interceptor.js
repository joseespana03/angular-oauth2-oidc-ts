import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout } from 'rxjs/operators';
import { OAuthResourceServerErrorHandler } from './resource-server-error-handler';
import { OAuthModuleConfig } from '../oauth-module.config';
import { OAuthStorage } from '../types';
import { OAuthService } from '../oauth-service';
export class DefaultOAuthInterceptor {
    constructor(authStorage, oAuthService, errorHandler, moduleConfig) {
        this.authStorage = authStorage;
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    checkUrl(url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find(u => url.startsWith(u));
        }
        return true;
    }
    intercept(req, next) {
        const url = req.url.toLowerCase();
        if (!this.moduleConfig ||
            !this.moduleConfig.resourceServer ||
            !this.checkUrl(url)) {
            return next.handle(req);
        }
        const sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError(err => this.errorHandler.handleError(err)));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter(token => (token ? true : false))), this.oAuthService.events.pipe(filter(e => e.type === 'token_received'), timeout(this.oAuthService.waitForTokenInMsec || 0), catchError(_ => of(null)), // timeout is not an error
        map(_ => this.oAuthService.getAccessToken()))).pipe(take(1), mergeMap(token => {
            if (token) {
                const header = 'Bearer ' + token;
                const headers = req.headers.set('Authorization', header);
                req = req.clone({ headers });
            }
            return next
                .handle(req)
                .pipe(catchError(err => this.errorHandler.handleError(err)));
        }));
    }
}
DefaultOAuthInterceptor.decorators = [
    { type: Injectable }
];
DefaultOAuthInterceptor.ctorParameters = () => [
    { type: OAuthStorage },
    { type: OAuthService },
    { type: OAuthResourceServerErrorHandler },
    { type: OAuthModuleConfig, decorators: [{ type: Optional }] }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9kaWVnby5hdXlvbi9Qcm9qZWN0cy90ZWx1cy9hbmd1bGFyLW9hdXRoMi1vaWRjL3Byb2plY3RzL2xpYi9zcmMvIiwic291cmNlcyI6WyJpbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLFFBQVEsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQVFyRCxPQUFPLEVBQWMsRUFBRSxFQUFFLEtBQUssRUFBRSxNQUFNLE1BQU0sQ0FBQztBQUM3QyxPQUFPLEVBQ0wsVUFBVSxFQUNWLE1BQU0sRUFDTixHQUFHLEVBQ0gsSUFBSSxFQUNKLFFBQVEsRUFDUixPQUFPLEVBQ1IsTUFBTSxnQkFBZ0IsQ0FBQztBQUN4QixPQUFPLEVBQUUsK0JBQStCLEVBQUUsTUFBTSxpQ0FBaUMsQ0FBQztBQUNsRixPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSx3QkFBd0IsQ0FBQztBQUMzRCxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sVUFBVSxDQUFDO0FBQ3hDLE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxrQkFBa0IsQ0FBQztBQUdoRCxNQUFNLE9BQU8sdUJBQXVCO0lBQ2xDLFlBQ1UsV0FBeUIsRUFDekIsWUFBMEIsRUFDMUIsWUFBNkMsRUFDakMsWUFBK0I7UUFIM0MsZ0JBQVcsR0FBWCxXQUFXLENBQWM7UUFDekIsaUJBQVksR0FBWixZQUFZLENBQWM7UUFDMUIsaUJBQVksR0FBWixZQUFZLENBQWlDO1FBQ2pDLGlCQUFZLEdBQVosWUFBWSxDQUFtQjtJQUNsRCxDQUFDO0lBRUksUUFBUSxDQUFDLEdBQVc7UUFDMUIsSUFBSSxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxtQkFBbUIsRUFBRTtZQUN4RCxPQUFPLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLG1C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dGlvbmFsIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcblxyXG5pbXBvcnQge1xyXG4gIEh0dHBFdmVudCxcclxuICBIdHRwSGFuZGxlcixcclxuICBIdHRwSW50ZXJjZXB0b3IsXHJcbiAgSHR0cFJlcXVlc3RcclxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XHJcbmltcG9ydCB7IE9ic2VydmFibGUsIG9mLCBtZXJnZSB9IGZyb20gJ3J4anMnO1xyXG5pbXBvcnQge1xyXG4gIGNhdGNoRXJyb3IsXHJcbiAgZmlsdGVyLFxyXG4gIG1hcCxcclxuICB0YWtlLFxyXG4gIG1lcmdlTWFwLFxyXG4gIHRpbWVvdXRcclxufSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XHJcbmltcG9ydCB7IE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIgfSBmcm9tICcuL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyJztcclxuaW1wb3J0IHsgT0F1dGhNb2R1bGVDb25maWcgfSBmcm9tICcuLi9vYXV0aC1tb2R1bGUuY29uZmlnJztcclxuaW1wb3J0IHsgT0F1dGhTdG9yYWdlIH0gZnJvbSAnLi4vdHlwZXMnO1xyXG5pbXBvcnQgeyBPQXV0aFNlcnZpY2UgfSBmcm9tICcuLi9vYXV0aC1zZXJ2aWNlJztcclxuXHJcbkBJbmplY3RhYmxlKClcclxuZXhwb3J0IGNsYXNzIERlZmF1bHRPQXV0aEludGVyY2VwdG9yIGltcGxlbWVudHMgSHR0cEludGVyY2VwdG9yIHtcclxuICBjb25zdHJ1Y3RvcihcclxuICAgIHByaXZhdGUgYXV0aFN0b3JhZ2U6IE9BdXRoU3RvcmFnZSxcclxuICAgIHByaXZhdGUgb0F1dGhTZXJ2aWNlOiBPQXV0aFNlcnZpY2UsXHJcbiAgICBwcml2YXRlIGVycm9ySGFuZGxlcjogT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcixcclxuICAgIEBPcHRpb25hbCgpIHByaXZhdGUgbW9kdWxlQ29uZmlnOiBPQXV0aE1vZHVsZUNvbmZpZ1xyXG4gICkge31cclxuXHJcbiAgcHJpdmF0ZSBjaGVja1VybCh1cmw6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmN1c3RvbVVybFZhbGlkYXRpb24pIHtcclxuICAgICAgcmV0dXJuIHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmN1c3RvbVVybFZhbGlkYXRpb24odXJsKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuYWxsb3dlZFVybHMpIHtcclxuICAgICAgcmV0dXJuICEhdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuYWxsb3dlZFVybHMuZmluZCh1ID0+XHJcbiAgICAgICAgdXJsLnN0YXJ0c1dpdGgodSlcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdHJ1ZTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBpbnRlcmNlcHQoXHJcbiAgICByZXE6IEh0dHBSZXF1ZXN0PGFueT4sXHJcbiAgICBuZXh0OiBIdHRwSGFuZGxlclxyXG4gICk6IE9ic2VydmFibGU8SHR0cEV2ZW50PGFueT4+IHtcclxuICAgIGNvbnN0IHVybCA9IHJlcS51cmwudG9Mb3dlckNhc2UoKTtcclxuXHJcbiAgICBpZiAoXHJcbiAgICAgICF0aGlzLm1vZHVsZUNvbmZpZyB8fFxyXG4gICAgICAhdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIgfHxcclxuICAgICAgIXRoaXMuY2hlY2tVcmwodXJsKVxyXG4gICAgKSB7XHJcbiAgICAgIHJldHVybiBuZXh0LmhhbmRsZShyZXEpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHNlbmRBY2Nlc3NUb2tlbiA9IHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLnNlbmRBY2Nlc3NUb2tlbjtcclxuXHJcbiAgICBpZiAoIXNlbmRBY2Nlc3NUb2tlbikge1xyXG4gICAgICByZXR1cm4gbmV4dFxyXG4gICAgICAgIC5oYW5kbGUocmVxKVxyXG4gICAgICAgIC5waXBlKGNhdGNoRXJyb3IoZXJyID0+IHRoaXMuZXJyb3JIYW5kbGVyLmhhbmRsZUVycm9yKGVycikpKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gbWVyZ2UoXHJcbiAgICAgIG9mKHRoaXMub0F1dGhTZXJ2aWNlLmdldEFjY2Vzc1Rva2VuKCkpLnBpcGUoXHJcbiAgICAgICAgZmlsdGVyKHRva2VuID0+ICh0b2tlbiA/IHRydWUgOiBmYWxzZSkpXHJcbiAgICAgICksXHJcbiAgICAgIHRoaXMub0F1dGhTZXJ2aWNlLmV2ZW50cy5waXBlKFxyXG4gICAgICAgIGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJyksXHJcbiAgICAgICAgdGltZW91dCh0aGlzLm9BdXRoU2VydmljZS53YWl0Rm9yVG9rZW5Jbk1zZWMgfHwgMCksXHJcbiAgICAgICAgY2F0Y2hFcnJvcihfID0+IG9mKG51bGwpKSwgLy8gdGltZW91dCBpcyBub3QgYW4gZXJyb3JcclxuICAgICAgICBtYXAoXyA9PiB0aGlzLm9BdXRoU2VydmljZS5nZXRBY2Nlc3NUb2tlbigpKVxyXG4gICAgICApXHJcbiAgICApLnBpcGUoXHJcbiAgICAgIHRha2UoMSksXHJcbiAgICAgIG1lcmdlTWFwKHRva2VuID0+IHtcclxuICAgICAgICBpZiAodG9rZW4pIHtcclxuICAgICAgICAgIGNvbnN0IGhlYWRlciA9ICdCZWFyZXIgJyArIHRva2VuO1xyXG4gICAgICAgICAgY29uc3QgaGVhZGVycyA9IHJlcS5oZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsIGhlYWRlcik7XHJcbiAgICAgICAgICByZXEgPSByZXEuY2xvbmUoeyBoZWFkZXJzIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcmV0dXJuIG5leHRcclxuICAgICAgICAgIC5oYW5kbGUocmVxKVxyXG4gICAgICAgICAgLnBpcGUoY2F0Y2hFcnJvcihlcnIgPT4gdGhpcy5lcnJvckhhbmRsZXIuaGFuZGxlRXJyb3IoZXJyKSkpO1xyXG4gICAgICB9KVxyXG4gICAgKTtcclxuICB9XHJcbn1cclxuIl19
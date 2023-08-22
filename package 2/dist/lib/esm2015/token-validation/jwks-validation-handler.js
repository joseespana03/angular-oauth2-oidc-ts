import { NullValidationHandler } from './null-validation-handler';
const err = `PLEASE READ THIS CAREFULLY:

Beginning with angular-oauth2-oidc version 9, the JwksValidationHandler
has been moved to an library of its own. If you need it for implementing
OAuth2/OIDC **implicit flow**, please install it using npm:

  npm i angular-oauth2-oidc-jwks --save

After that, you can import it into your application:

  import { JwksValidationHandler } from 'angular-oauth2-oidc-jwks';

Please note, that this dependency is not needed for the **code flow**,
which is nowadays the **recommented** one for single page applications.
This also results in smaller bundle sizes.
`;
/**
 * This is just a dummy of the JwksValidationHandler
 * telling the users that the real one has been moved
 * to an library of its own, namely angular-oauth2-oidc-utils
 */
export class JwksValidationHandler extends NullValidationHandler {
    constructor() {
        super();
        console.error(err);
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiandrcy12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiQzovVXNlcnMvZGllZ28uYXV5b24vUHJvamVjdHMvdGVsdXMvYW5ndWxhci1vYXV0aDItb2lkYy9wcm9qZWN0cy9saWIvc3JjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9qd2tzLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUscUJBQXFCLEVBQUUsTUFBTSwyQkFBMkIsQ0FBQztBQUVsRSxNQUFNLEdBQUcsR0FBRzs7Ozs7Ozs7Ozs7Ozs7O0NBZVgsQ0FBQztBQUVGOzs7O0dBSUc7QUFDSCxNQUFNLE9BQU8scUJBQXNCLFNBQVEscUJBQXFCO0lBQzlEO1FBQ0UsS0FBSyxFQUFFLENBQUM7UUFDUixPQUFPLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3JCLENBQUM7Q0FDRiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE51bGxWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJy4vbnVsbC12YWxpZGF0aW9uLWhhbmRsZXInO1xyXG5cclxuY29uc3QgZXJyID0gYFBMRUFTRSBSRUFEIFRISVMgQ0FSRUZVTExZOlxyXG5cclxuQmVnaW5uaW5nIHdpdGggYW5ndWxhci1vYXV0aDItb2lkYyB2ZXJzaW9uIDksIHRoZSBKd2tzVmFsaWRhdGlvbkhhbmRsZXJcclxuaGFzIGJlZW4gbW92ZWQgdG8gYW4gbGlicmFyeSBvZiBpdHMgb3duLiBJZiB5b3UgbmVlZCBpdCBmb3IgaW1wbGVtZW50aW5nXHJcbk9BdXRoMi9PSURDICoqaW1wbGljaXQgZmxvdyoqLCBwbGVhc2UgaW5zdGFsbCBpdCB1c2luZyBucG06XHJcblxyXG4gIG5wbSBpIGFuZ3VsYXItb2F1dGgyLW9pZGMtandrcyAtLXNhdmVcclxuXHJcbkFmdGVyIHRoYXQsIHlvdSBjYW4gaW1wb3J0IGl0IGludG8geW91ciBhcHBsaWNhdGlvbjpcclxuXHJcbiAgaW1wb3J0IHsgSndrc1ZhbGlkYXRpb25IYW5kbGVyIH0gZnJvbSAnYW5ndWxhci1vYXV0aDItb2lkYy1qd2tzJztcclxuXHJcblBsZWFzZSBub3RlLCB0aGF0IHRoaXMgZGVwZW5kZW5jeSBpcyBub3QgbmVlZGVkIGZvciB0aGUgKipjb2RlIGZsb3cqKixcclxud2hpY2ggaXMgbm93YWRheXMgdGhlICoqcmVjb21tZW50ZWQqKiBvbmUgZm9yIHNpbmdsZSBwYWdlIGFwcGxpY2F0aW9ucy5cclxuVGhpcyBhbHNvIHJlc3VsdHMgaW4gc21hbGxlciBidW5kbGUgc2l6ZXMuXHJcbmA7XHJcblxyXG4vKipcclxuICogVGhpcyBpcyBqdXN0IGEgZHVtbXkgb2YgdGhlIEp3a3NWYWxpZGF0aW9uSGFuZGxlclxyXG4gKiB0ZWxsaW5nIHRoZSB1c2VycyB0aGF0IHRoZSByZWFsIG9uZSBoYXMgYmVlbiBtb3ZlZFxyXG4gKiB0byBhbiBsaWJyYXJ5IG9mIGl0cyBvd24sIG5hbWVseSBhbmd1bGFyLW9hdXRoMi1vaWRjLXV0aWxzXHJcbiAqL1xyXG5leHBvcnQgY2xhc3MgSndrc1ZhbGlkYXRpb25IYW5kbGVyIGV4dGVuZHMgTnVsbFZhbGlkYXRpb25IYW5kbGVyIHtcclxuICBjb25zdHJ1Y3RvcigpIHtcclxuICAgIHN1cGVyKCk7XHJcbiAgICBjb25zb2xlLmVycm9yKGVycik7XHJcbiAgfVxyXG59XHJcbiJdfQ==
import { Injectable } from '@angular/core';
export class UrlHelperService {
    getHashFragmentParams(customHashFragment) {
        let hash = customHashFragment || window.location.hash;
        hash = decodeURIComponent(hash);
        if (hash.indexOf('#') !== 0) {
            return {};
        }
        const questionMarkPosition = hash.indexOf('?');
        if (questionMarkPosition > -1) {
            hash = hash.substr(questionMarkPosition + 1);
        }
        else {
            hash = hash.substr(1);
        }
        return this.parseQueryString(hash);
    }
    parseQueryString(queryString) {
        const data = {};
        let pairs, pair, separatorIndex, escapedKey, escapedValue, key, value;
        if (queryString === null) {
            return data;
        }
        pairs = queryString.split('&');
        for (let i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf('=');
            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            }
            else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }
            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);
            if (key.substr(0, 1) === '/') {
                key = key.substr(1);
            }
            data[key] = value;
        }
        return data;
    }
}
UrlHelperService.decorators = [
    { type: Injectable }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXJsLWhlbHBlci5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL2RpZWdvLmF1eW9uL1Byb2plY3RzL3RlbHVzL2FuZ3VsYXItb2F1dGgyLW9pZGMvcHJvamVjdHMvbGliL3NyYy8iLCJzb3VyY2VzIjpbInVybC1oZWxwZXIuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBRzNDLE1BQU0sT0FBTyxnQkFBZ0I7SUFDcEIscUJBQXFCLENBQUMsa0JBQTJCO1FBQ3RELElBQUksSUFBSSxHQUFHLGtCQUFrQixJQUFJLE1BQU0sQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDO1FBRXRELElBQUksR0FBRyxrQkFBa0IsQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUVoQyxJQUFJLElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxFQUFFO1lBQzNCLE9BQU8sRUFBRSxDQUFDO1NBQ1g7UUFFRCxNQUFNLG9CQUFvQixHQUFHLElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUM7UUFFL0MsSUFBSSxvQkFBb0IsR0FBRyxDQUFDLENBQUMsRUFBRTtZQUM3QixJQUFJLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxvQkFBb0IsR0FBRyxDQUFDLENBQUMsQ0FBQztTQUM5QzthQUFNO1lBQ0wsSUFBSSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDdkI7UUFFRCxPQUFPLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUNyQyxDQUFDO0lBRU0sZ0JBQWdCLENBQUMsV0FBbUI7UUFDekMsTUFBTSxJQUFJLEdBQUcsRUFBRSxDQUFDO1FBQ2hCLElBQUksS0FBSyxFQUFFLElBQUksRUFBRSxjQUFjLEVBQUUsVUFBVSxFQUFFLFlBQVksRUFBRSxHQUFHLEVBQUUsS0FBSyxDQUFDO1FBRXRFLElBQUksV0FBVyxLQUFLLElBQUksRUFBRTtZQUN4QixPQUFPLElBQUksQ0FBQztTQUNiO1FBRUQsS0FBSyxHQUFHLFdBQVcsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUM7UUFFL0IsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLEtBQUssQ0FBQyxNQUFNLEVBQUUsQ0FBQyxFQUFFLEVBQUU7WUFDckMsSUFBSSxHQUFHLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUNoQixjQUFjLEdBQUcsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUVuQyxJQUFJLGNBQWMsS0FBSyxDQUFDLENBQUMsRUFBRTtnQkFDekIsVUFBVSxHQUFHLElBQUksQ0FBQztnQkFDbEIsWUFBWSxHQUFHLElBQUksQ0FBQzthQUNyQjtpQkFBTTtnQkFDTCxVQUFVLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsY0FBYyxDQUFDLENBQUM7Z0JBQzVDLFlBQVksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLGNBQWMsR0FBRyxDQUFDLENBQUMsQ0FBQzthQUNoRDtZQUVELEdBQUcsR0FBRyxrQkFBa0IsQ0FBQyxVQUFVLENBQUMsQ0FBQztZQUNyQyxLQUFLLEdBQUcsa0JBQWtCLENBQUMsWUFBWSxDQUFDLENBQUM7WUFFekMsSUFBSSxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsS0FBSyxHQUFHLEVBQUU7Z0JBQzVCLEdBQUcsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO2FBQ3JCO1lBRUQsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEtBQUssQ0FBQztTQUNuQjtRQUVELE9BQU8sSUFBSSxDQUFDO0lBQ2QsQ0FBQzs7O1lBdkRGLFVBQVUiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcblxyXG5ASW5qZWN0YWJsZSgpXHJcbmV4cG9ydCBjbGFzcyBVcmxIZWxwZXJTZXJ2aWNlIHtcclxuICBwdWJsaWMgZ2V0SGFzaEZyYWdtZW50UGFyYW1zKGN1c3RvbUhhc2hGcmFnbWVudD86IHN0cmluZyk6IG9iamVjdCB7XHJcbiAgICBsZXQgaGFzaCA9IGN1c3RvbUhhc2hGcmFnbWVudCB8fCB3aW5kb3cubG9jYXRpb24uaGFzaDtcclxuXHJcbiAgICBoYXNoID0gZGVjb2RlVVJJQ29tcG9uZW50KGhhc2gpO1xyXG5cclxuICAgIGlmIChoYXNoLmluZGV4T2YoJyMnKSAhPT0gMCkge1xyXG4gICAgICByZXR1cm4ge307XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgcXVlc3Rpb25NYXJrUG9zaXRpb24gPSBoYXNoLmluZGV4T2YoJz8nKTtcclxuXHJcbiAgICBpZiAocXVlc3Rpb25NYXJrUG9zaXRpb24gPiAtMSkge1xyXG4gICAgICBoYXNoID0gaGFzaC5zdWJzdHIocXVlc3Rpb25NYXJrUG9zaXRpb24gKyAxKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIGhhc2ggPSBoYXNoLnN1YnN0cigxKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGhpcy5wYXJzZVF1ZXJ5U3RyaW5nKGhhc2gpO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIHBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XHJcbiAgICBjb25zdCBkYXRhID0ge307XHJcbiAgICBsZXQgcGFpcnMsIHBhaXIsIHNlcGFyYXRvckluZGV4LCBlc2NhcGVkS2V5LCBlc2NhcGVkVmFsdWUsIGtleSwgdmFsdWU7XHJcblxyXG4gICAgaWYgKHF1ZXJ5U3RyaW5nID09PSBudWxsKSB7XHJcbiAgICAgIHJldHVybiBkYXRhO1xyXG4gICAgfVxyXG5cclxuICAgIHBhaXJzID0gcXVlcnlTdHJpbmcuc3BsaXQoJyYnKTtcclxuXHJcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHBhaXJzLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgIHBhaXIgPSBwYWlyc1tpXTtcclxuICAgICAgc2VwYXJhdG9ySW5kZXggPSBwYWlyLmluZGV4T2YoJz0nKTtcclxuXHJcbiAgICAgIGlmIChzZXBhcmF0b3JJbmRleCA9PT0gLTEpIHtcclxuICAgICAgICBlc2NhcGVkS2V5ID0gcGFpcjtcclxuICAgICAgICBlc2NhcGVkVmFsdWUgPSBudWxsO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIGVzY2FwZWRLZXkgPSBwYWlyLnN1YnN0cigwLCBzZXBhcmF0b3JJbmRleCk7XHJcbiAgICAgICAgZXNjYXBlZFZhbHVlID0gcGFpci5zdWJzdHIoc2VwYXJhdG9ySW5kZXggKyAxKTtcclxuICAgICAgfVxyXG5cclxuICAgICAga2V5ID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZWRLZXkpO1xyXG4gICAgICB2YWx1ZSA9IGRlY29kZVVSSUNvbXBvbmVudChlc2NhcGVkVmFsdWUpO1xyXG5cclxuICAgICAgaWYgKGtleS5zdWJzdHIoMCwgMSkgPT09ICcvJykge1xyXG4gICAgICAgIGtleSA9IGtleS5zdWJzdHIoMSk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGRhdGFba2V5XSA9IHZhbHVlO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBkYXRhO1xyXG4gIH1cclxufVxyXG4iXX0=
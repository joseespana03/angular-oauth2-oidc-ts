import { MemoryStorage } from './types';
export function createDefaultLogger() {
    return console;
}
export function createDefaultStorage() {
    return typeof sessionStorage !== 'undefined'
        ? sessionStorage
        : new MemoryStorage();
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZmFjdG9yaWVzLmpzIiwic291cmNlUm9vdCI6IkM6L1VzZXJzL2RpZWdvLmF1eW9uL1Byb2plY3RzL3RlbHVzL2FuZ3VsYXItb2F1dGgyLW9pZGMvcHJvamVjdHMvbGliL3NyYy8iLCJzb3VyY2VzIjpbImZhY3Rvcmllcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sU0FBUyxDQUFDO0FBRXhDLE1BQU0sVUFBVSxtQkFBbUI7SUFDakMsT0FBTyxPQUFPLENBQUM7QUFDakIsQ0FBQztBQUVELE1BQU0sVUFBVSxvQkFBb0I7SUFDbEMsT0FBTyxPQUFPLGNBQWMsS0FBSyxXQUFXO1FBQzFDLENBQUMsQ0FBQyxjQUFjO1FBQ2hCLENBQUMsQ0FBQyxJQUFJLGFBQWEsRUFBRSxDQUFDO0FBQzFCLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBNZW1vcnlTdG9yYWdlIH0gZnJvbSAnLi90eXBlcyc7XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlRGVmYXVsdExvZ2dlcigpIHtcclxuICByZXR1cm4gY29uc29sZTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGNyZWF0ZURlZmF1bHRTdG9yYWdlKCkge1xyXG4gIHJldHVybiB0eXBlb2Ygc2Vzc2lvblN0b3JhZ2UgIT09ICd1bmRlZmluZWQnXHJcbiAgICA/IHNlc3Npb25TdG9yYWdlXHJcbiAgICA6IG5ldyBNZW1vcnlTdG9yYWdlKCk7XHJcbn1cclxuIl19
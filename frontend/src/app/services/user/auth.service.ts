import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';
import { LoginRequest, LoginResponse } from '../../models/user/user';


@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8000/api/users';
  private loggedIn = new BehaviorSubject<boolean>(this.hasToken());

  constructor(private http: HttpClient) {}
  private getAuthHeaders(): HttpHeaders {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    
    if (!token || !role) {
      throw new Error('Token or Role is missing!');
    }

    // Vraća zaglavlje sa tokenom i rodom
    return new HttpHeaders().set('Authorization', `Bearer ${token}`).set('Role', role);
  }

  // Funkcija za prijavljivanje korisnika
  login(credentials: LoginRequest): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/login`, credentials).pipe(
      tap((response: LoginResponse) => {
        // Čuvanje tokena u localStorage
        localStorage.setItem('token', response.token);
        localStorage.setItem('username', response.username);
        localStorage.setItem('role', response.role);
        this.loggedIn.next(true);
      })
    );
  }
  sendPasswordResetLink(username: string, email: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/forgot-password`, { username, email });
  }

  sendMagicLink(username: string, email: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/magic-link`, { username, email });
  }

  verifyMagicLink(token: string): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/magic-login?token=${token}`);
  }
  
  
  checkUsername(username: string): Observable<any> {
    const headers = this.getAuthHeaders();
    return this.http.get(`${this.apiUrl}/check-username/${username}`, { headers });
  }

  isLoggedIn(): Observable<boolean> {
    return this.loggedIn.asObservable();
  }

  logout(): void {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    this.loggedIn.next(false);
  }

  // Dobijanje tokena iz localStorage
  getToken(): string | null {
    return localStorage.getItem('token');
  }

  // Dobijanje uloge korisnika
  getUserRole(): string | null {
    return localStorage.getItem('role');
  }

  isAuthorized(roles: string[]): boolean {
    const userRole = this.getUserRole();
    return userRole ? roles.includes(userRole) : false;
  }

  // Funkcija za proveru da li postoji token u localStorage
  private hasToken(): boolean {
    return !!localStorage.getItem('token');
  }
  hasRole(role: string): boolean {
    const userRole = this.getUserRole();
    return userRole === role;
  }
  

  getUserProfile(): Observable<any> {
    const headers = this.getAuthHeaders();
    return this.http.get<any>(`${this.apiUrl}/users-profile`, { headers });
  }

  resetPassword(token: string, newPassword: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/reset-password`, { token, newPassword });
  }
  
  
}

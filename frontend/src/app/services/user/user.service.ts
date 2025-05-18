import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = 'http://localhost:8000/api/users/change-password'; 

  constructor(private http: HttpClient) { }
  private getAuthHeaders(): HttpHeaders {
    const token = localStorage.getItem('token'); // JWT token iz localStorage
    const role = localStorage.getItem('role'); // Uloga korisnika iz localStorage
    if (!token || !role) {
      throw new Error('Token or Role is missing!');
    }

    // Vraća zaglavlje sa tokenom i rodom
    return new HttpHeaders()
      .set('Authorization', `Bearer ${token}`)
      .set('Role', role); // Dodaje role u zaglavlje
  }

  changePassword(oldPassword: string, newPassword: string, confirmPassword: string): Observable<any> {
    const headers = this.getAuthHeaders(); // Koristi token i role za autorizaciju
    const body = { oldPassword, newPassword, confirmPassword };
    return this.http.post(this.apiUrl, body, { headers });
  }
}
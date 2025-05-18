import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class NotificationService {
  private apiUrl = 'http://localhost:8000/api/notifications';
  private getUrl = 'http://localhost:8000/api/notifications/all';

  constructor(private http: HttpClient) {}
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

  // Dohvati notifikacije korisnika
  getNotifications(username: string): Observable<any[]> {
    const headers = this.getAuthHeaders();
    return this.http.get<any[]>(`${this.getUrl}?username=${username}`, { headers });
  }


  // Označi notifikaciju kao pročitanu
  markAsRead(notificationId: string, username: string): Observable<any> {
    const headers = this.getAuthHeaders();
    const body = { notificationId, username };
    return this.http.put(`${this.apiUrl}/read`, body, { headers });
  }
}

import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})

export class TaskService {
  private apiUrl = 'http://localhost:8000/api/tasks';
  private projectUrl = 'http://localhost:8000/api/projects';


  constructor(private http: HttpClient) {}
  private getAuthHeaders(): HttpHeaders {
    const token = localStorage.getItem('token'); // Uzima token iz localStorage
    const role = localStorage.getItem('role'); // Uzima ulogu iz localStorage
    if (!token || !role) {
      throw new Error('Token or Role is missing'); // Bacanje greške ako token ili role ne postoji
    }
    return new HttpHeaders({
      'Authorization': `Bearer ${token}`,
      'Role': role, // Dodavanje Role header-a
      'Content-Type': 'application/json'
    });
  }

  createTask(taskData: { projectId: string; title: string; description: string }): Observable<any> {
    const headers = this.getAuthHeaders();
    return this.http.post(`${this.apiUrl}/create`, taskData, { headers });
  }

  getAllTasks(): Observable<any[]> {
    const headers = this.getAuthHeaders();
    return this.http.get<any[]>(`${this.apiUrl}/all`, { headers });
  }
  
  getTasksByProject(projectId: string): Observable<any[]> {
    const headers = this.getAuthHeaders();
    return this.http.get<any[]>(`${this.apiUrl}/project/${projectId}`, { headers });
  }

  getTasksForProject(projectId: string): Observable<any[]> {
    const headers = this.getAuthHeaders();
    return this.http.get<any[]>(`${this.projectUrl}/${projectId}/tasks`, { headers });
  }
  
  
  updateTaskStatus(taskId: string, status: string): Observable<any> {
    const headers = this.getAuthHeaders();
    const url = `${this.apiUrl}/status`;
    const username = localStorage.getItem('username');
    const body = { taskId, status, username };

    console.log('Sending request to update status:', body);

    return this.http.post(url, body, { headers });
  }

  getAvailableMembers(projectId: string, taskId: string): Observable<any[]> {
    const headers = this.getAuthHeaders();
    const apiUrl = `http://localhost:8002/api/tasks/${taskId}/project/${projectId}/available-members`;
    return this.http.get<any[]>(apiUrl, { headers });
  }
  

  addMembersToTask(taskId: string, members: any[]): Observable<any> {
    const headers = this.getAuthHeaders();
    const apiUrl = `http://localhost:8002/api/tasks/${taskId}/add-members`;
    return this.http.post(apiUrl, members, { headers });
  }
  
  getTaskMembers(taskId: string): Observable<any> {
    const headers = this.getAuthHeaders();
    const apiUrl = `http://localhost:8002/api/tasks/${taskId}/members`;
    return this.http.get(apiUrl, { headers });
  }

  removeMemberFromTask(taskId: string, memberId: string): Observable<any> {
    const headers = this.getAuthHeaders();
    const apiUrl = `http://localhost:8002/api/tasks/${taskId}/members/${memberId}`;
    return this.http.delete(apiUrl, { headers });
  }
}

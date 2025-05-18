import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { catchError, Observable, throwError } from 'rxjs';
import { Project } from '../../models/project/project';

@Injectable({
  providedIn: 'root'
})
export class ProjectService {

  updateTaskStatus(id: any, status: any) {
    throw new Error('Method not implemented.');
  }

  private apiUrl = 'http://localhost:8000/api/projects';


  private mainUrl = 'http://localhost:8000/api';

  private addUrl = 'http://localhost:8000/api/projects/add';


  constructor(private http: HttpClient) {}

  private getHeadersWithRole(): HttpHeaders {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');

    if (!token || !role) {
      console.error('Token or Role missing');
      return new HttpHeaders(); // Return empty headers if missing
    }

    return new HttpHeaders({
      Authorization: `Bearer ${token}`,
      Role: role,
    });
  }

   createProject(projectData: { name: string; expectedEndDate: string; minMembers: number; maxMembers: number }): Observable<any> {
    const headers = this.getHeadersWithRole();
    return this.http
      .post(this.addUrl, projectData, { headers })
      .pipe(
        catchError((error) => {
          console.error('Error creating project:', error);
          return throwError('Failed to create project');
        })
      );
  }
  

  getProjects(): Observable<Project[]> {
    const headers = this.getHeadersWithRole();
    return this.http
      .get<Project[]>(`${this.apiUrl}/all`, { headers })
      .pipe(
        catchError((error) => {
          console.error('Error fetching projects:', error);
          return throwError('Failed to fetch projects');
        })
      );
  }

  getProjectById(id: string): Observable<Project> {
    const headers = this.getHeadersWithRole();
    return this.http
      .get<Project>(`${this.apiUrl}/${id}`, { headers })
      .pipe(
        catchError((error) => {
          console.error('Error fetching project by ID:', error);
          return throwError('Failed to fetch project by ID');
        })
      );
  }
  
  getTasksForProject(projectId: string): Observable<any[]> {
    const headers = this.getHeadersWithRole();
    return this.http
      .get<any[]>(`${this.apiUrl}/${projectId}/tasks`, { headers })
      .pipe(
        catchError((error) => {
          console.error('Error fetching tasks for project:', error);
          return throwError('Failed to fetch tasks for project');
        })
      );
  }
  getProjectsByUsername(username: string): Observable<Project[]> {
    const headers = this.getHeadersWithRole();
    return this.http
      .get<Project[]>(`${this.apiUrl}/username/${username}`, { headers })
      .pipe(
        catchError((error) => {
          console.error('Error fetching projects by username:', error);
          return throwError('Failed to fetch projects by username');
        })
      );
  }
  deleteProject(projectId: string): Observable<any> {
    const headers = this.getHeadersWithRole(); // Koristi header sa tokenom i ulogom
    return this.http
      .delete(`${this.apiUrl}/${projectId}`, { headers })
      .pipe(
        catchError((error) => {
          console.error('Error deleting project:', error);
          return throwError('Failed to delete project');
        })
      );
  }
}  
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { ProjectService } from '../../services/project/project.service';
import { Project } from '../../models/project/project';
import { CommonModule, DatePipe } from '@angular/common';
import { jwtDecode } from 'jwt-decode';

@Component({
  selector: 'app-users-projects',
  standalone: true,
  imports: [CommonModule],
  providers: [DatePipe],
  templateUrl: './users-projects.component.html',
  styleUrls: ['./users-projects.component.css']
})
export class UsersProjectsComponent implements OnInit {
  projects: Project[] = [];

  constructor(private projectService: ProjectService, private router: Router) {}

  ngOnInit(): void {
    const token = localStorage.getItem('token'); 
    
    if (!token) {
      console.error('User not logged in');
      return;
    }
    
    try {
      const decodedToken: any = jwtDecode(token);
      const username = decodedToken.username; 
      
      console.log("Decoded username:", username);   

      this.projectService.getProjectsByUsername(username).subscribe(
        (data) => {
          console.log("Fetched projects for user:", data);
         
          this.projects = data ? data.filter((project) => 
            project.members.some(member => member.username === username)
          ) : [];
        },
        (error) => {
          console.error('Error fetching projects:', error);
        }
      );
    } catch (error) {
      console.error('Error decoding token:', error);
    }
  }

  openDetails(project: Project): void {
    this.router.navigate(['/project', project.id]);
  }
}

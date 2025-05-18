import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { ProjectService } from '../../services/project/project.service';
import { Project } from '../../models/project/project';
import { CommonModule, DatePipe } from '@angular/common';

@Component({
  selector: 'app-project-list',
  standalone: true,
  imports: [CommonModule],
  providers: [DatePipe],
  templateUrl: './project-list.component.html',
  styleUrls: ['./project-list.component.css']
})
export class ProjectListComponent implements OnInit {
  projects: Project[] = [];
  errorMessage: string = '';

  constructor(private projectService: ProjectService, private router: Router) {}

  ngOnInit(): void {
    this.projectService.getProjects().subscribe(
      (data) => {
        console.log("Fetched projects:", data);
        this.projects = data ? data.map((project) => ({
          ...project,
          expectedEndDate: new Date(project.expectedEndDate as string)
        })) : [];
        this.errorMessage = ''; // Reset greške ako je sve prošlo kako treba
      },
      (error) => {
        console.error('Error fetching projects:', error);
        this.errorMessage = error.message; // Postavi poruku o grešci
      }
    );
  }

  // Navigacija na stranicu sa detaljima projekta
  openDetails(project: Project): void {
    this.router.navigate(['/project', project.id]);
  }
}

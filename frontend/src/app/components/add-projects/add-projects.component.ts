import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ProjectService } from '../../services/project/project.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-add-projects',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './add-projects.component.html',
  styleUrls: ['./add-projects.component.css']
})
export class AddProjectsComponent {
  projectForm: FormGroup;
  successMessage: string | null = null;
  errorMessage: string | null = null;

  constructor(
    private fb: FormBuilder, 
    private projectService: ProjectService,
    private router: Router
  ) {
    this.projectForm = this.fb.group({
      name: ['', Validators.required],
      expectedEndDate: ['', Validators.required],
      minMembers: ['', [Validators.required, Validators.min(1)]],
      maxMembers: ['', [Validators.required, Validators.min(1)]],
    });
  }

  onSubmit() {
    if (this.projectForm.valid) {
      const projectData = {
        ...this.projectForm.value,
        expectedEndDate: new Date(this.projectForm.value.expectedEndDate).toISOString(),
      };
  
      this.projectService.createProject(projectData).subscribe(
        response => {
          this.successMessage = 'Project successfully created!';
        this.errorMessage = null;
        this.projectForm.reset();
        this.router.navigate(['/projects-list']); 
      },
        error => {
          if (error.status === 400) {
            if (error.error.includes("Expected end date must be in the future")) {
              this.errorMessage = "Expected end date must be in the future.";
            } else if (error.error.includes("Invalid member constraints")) {
              this.errorMessage = "Minimum members must be at least 1, and maximum members cannot be less than minimum members.";
            } else if (error.error.includes("Project name is required")) {
              this.errorMessage = "Project name is required.";
            } else {
              this.errorMessage = "Invalid request. Please check your input.";
            }
          } else if (error.status === 401) {
            this.errorMessage = "Unauthorized: Please log in to create a project.";    
          }else if (error.status === 409) {
            this.errorMessage = "A project with this name already exists. Please choose a different name.";
          } else {
            this.errorMessage = "Failed to create project.";
          }

          this.successMessage = null;
          setTimeout(() => {
            this.errorMessage = null;
          }, 3000);
        }
      );
    } else {
      this.errorMessage = 'Please fill out all required fields.';
      setTimeout(() => {
        this.errorMessage = null;
      }, 3000);
    }
  }
}

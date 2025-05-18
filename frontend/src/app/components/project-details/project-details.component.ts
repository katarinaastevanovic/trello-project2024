import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, NavigationEnd, Router } from '@angular/router';
import { ProjectService } from '../../services/project/project.service';
import { Project } from '../../models/project/project';
import { CommonModule, DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { TaskService } from '../../services/task/task.service';
import { AuthService } from '../../services/user/auth.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-project-details',
  standalone: true,
  imports: [CommonModule, FormsModule],
  providers: [DatePipe],
  templateUrl: './project-details.component.html',
  styleUrls: ['./project-details.component.css']
})
export class ProjectDetailsComponent implements OnInit {
  project: Project | null = null;
  tasks: any[] = [];
  isLoading = false;
  isManager: boolean = false;
  isMember: boolean = false;
  isAuthenticated: boolean = false;
  showDeleteConfirmation: boolean = false; 
  errorMessage: string = '';
  successMessage: string = '';
  private subscription: Subscription = new Subscription();


  constructor(
    private route: ActivatedRoute,
    private projectService: ProjectService,
    private datePipe: DatePipe,
    private router: Router,
    private taskService: TaskService,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.checkUserRole(); // Initial role check
    this.listenToRouterEvents(); // Update roles on route change

    const projectId = this.route.snapshot.paramMap.get('id');
    if (projectId) {
      this.loadProjectAndTasks(projectId);
    } else {
      this.errorMessage = 'Invalid Project ID. Redirecting to the projects list.';
      setTimeout(() => {
        this.errorMessage = '';
      }, 5000);
      //this.router.navigate(['/projects']);
      this.router.navigate(['/projects-list']);
    }
  }
  checkUserRole(): void {
    const role = this.authService.getUserRole();
    this.isAuthenticated = !!role;
    this.isManager = role === 'manager';
    this.isMember = role === 'member';
  }

  listenToRouterEvents(): void {
    this.subscription.add(
      this.router.events.subscribe((event) => {
        if (event instanceof NavigationEnd) {
          this.checkUserRole();
        }
      })
    );
  }
  

  loadProjectAndTasks(projectId: string): void {
    this.isLoading = true;
    this.projectService.getProjectById(projectId).subscribe(
      (data) => {
        this.project = data;
        console.log('Project details fetched:', this.project);
        this.getTasks(projectId);
      },
      (error) => {
        console.error('Error fetching project details:', error);
        this.isLoading = false;
      }
    );
  }

  getTasks(projectId: string): void {
    this.projectService.getTasksForProject(projectId).subscribe(
      (tasks) => {
        this.tasks = tasks || [];
      },
      (error) => {
        console.error('Error fetching tasks:', error);
      }
    );
  }
  openAddMembersToTask(taskId: string): void {
    const projectId = this.project?.id;
    if (projectId) {
      this.router.navigate([`/project/${projectId}/task/${taskId}/add-members`]);
    }
  }
  
  viewMembersToTask(taskId: string): void {
    const projectId = this.project?.id;
    if (projectId) {
      this.router.navigate([`/project/${projectId}/task/${taskId}/members`]);
    } else {
      console.error('Project ID is not available.');
    }}
  getTaskDependencyTitle(task: any): string | null {
    console.log('Checking dependency for task:', task);

    if (task.dependsOn) {
      const dependentTask = this.tasks.find(
        t => t.id === task.dependsOn || t.id === task.dependsOn?.toString()
      );

      if (dependentTask) {
        console.log(`Dependent task found: ${dependentTask.title}`);
        return dependentTask.title;
      } else {
        console.warn(`Dependent task not found for ID: ${task.dependsOn}`);
        return 'Dependency not found';
      }
    }
    return null;
  }

  updateTaskStatus(task: any): void {
    if (!task || !task.id || !task.status) {
      this.errorMessage = 'Cannot update task status. Task data is invalid.';
      setTimeout(() => {
        this.errorMessage = '';
      }, 5000);
      return;
    }

    // Check for dependencies
    if (task.dependsOn) {
      const dependentTask = this.tasks.find(t => t.id === task.dependsOn);
      if (
        dependentTask &&
        dependentTask.status !== 'Completed' &&
        task.status !== 'Pending'
      ) {
        this.errorMessage = `Cannot change status to "${task.status}" because dependent task "${dependentTask.title}" is not completed.`;
        setTimeout(() => {
          this.errorMessage = '';
        }, 5000);
        return;
      }
    }

    const payload = {
      taskId: task.id,
      status: task.status,
      username: localStorage.getItem('username') 
    };
  
    console.log('Payload za ažuriranje statusa taska:', payload);

    console.log(
      `Attempting to update status for task "${task.title}" to "${task.status}"`
    );

    this.taskService.updateTaskStatus(task.id, task.status).subscribe({
      next: () => {
        this.successMessage = `Status for task "${task.title}" successfully updated to "${task.status}".`;
        setTimeout(() => {
          this.successMessage = '';
        }, 5000);
        this.getTasks(this.project?.id!); // Refresh tasks
      },
      error: (err: any) => {
        console.error('Error updating task status:', err);
        this.errorMessage = `Failed to update status for task "${task.title}". Please try again later.`;
        setTimeout(() => {
          this.errorMessage = '';
        }, 5000);
      }
    });
  }

  goBack(): void {
    window.history.back();
  }

  addTask(): void {
    if (this.project) {
      this.router.navigate(['/add-tasks', { projectId: this.project.id }]);
    }
  }

  viewMembers(): void {
    if (this.project) {
      this.router.navigate(['/remove-members', this.project.id]);
    }
  }

  addMember(): void {
    const projectId = this.project?.id;
    if (projectId) {
      this.router.navigate([`/project/${projectId}/add-members`]);
    }
  }
  ngOnDestroy(): void {
    this.subscription.unsubscribe(); // Clean up subscriptions
  }

  confirmDelete(): void {
    this.showDeleteConfirmation = true; // Prikaži modal
  }

  cancelDelete(): void {
    this.showDeleteConfirmation = false; // Sakrij modal
  }

  deleteProject(): void {
    if (!this.project) {
      console.error('No project to delete');
      return;
    }

    this.projectService.deleteProject(this.project.id).subscribe({
      next: () => {
        this.successMessage = 'Project deleted successfully!';
        setTimeout(() => {
          this.successMessage = '';
        }, 5000);

        this.router.navigate(['/projects-list']); 
      },
      error: (err) => {
        console.error('Failed to delete project:', err);
        this.errorMessage = 'Failed to delete project. Please try again later.';
        setTimeout(() => {
          this.errorMessage = '';
        }, 5000);

      },
    });

    this.showDeleteConfirmation = false; 
  }
}



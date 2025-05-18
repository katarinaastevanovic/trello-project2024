import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup } from '@angular/forms';
import { TaskService } from '../../services/task/task.service';
import { Router, ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-create-task',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './add-tasks.component.html',
  styleUrls: ['./add-tasks.component.css']
})
export class AddTasksComponent {
  showForm: boolean = true;
  taskForm: FormGroup;
  successMessage: string = '';
  errorMessage: string = '';
  tasks: any[] = [];

  constructor(
    private fb: FormBuilder,
    private taskService: TaskService,
    private router: Router,
    private route: ActivatedRoute
  ) {
    this.taskForm = this.fb.group({
      projectId: [''],
      title: [''],
      description: [''],
      dependsOn: [''],
      status: ['Pending']
    });

    this.route.params.subscribe(params => {
      const projectId = params['projectId'];
      if (projectId) {
        this.taskForm.get('projectId')?.setValue(projectId);
      }
    });
  }

  ngOnInit(): void {
    this.route.params.subscribe(params => {
      const projectId = params['projectId'];
      if (projectId) {
        this.taskForm.get('projectId')?.setValue(projectId);
        console.log('Project ID:', projectId);
        this.loadProjectTasks(projectId); 
      }
    });
  }
  
  
  loadProjectTasks(projectId: string): void {
    this.taskService.getTasksForProject(projectId).subscribe(
      (tasks: any[] | null) => {
        this.tasks = tasks || [];
        console.log('Tasks fetched for project:', this.tasks); // Log za debug
      },
      (error: any) => {
        console.error('Error fetching tasks:', error); // Log za grešku
      }
    );
  }
  

  
  

  toggleForm() {
    this.showForm = !this.showForm;
  }

  isValidTaskData(taskData: any): boolean {
    return (
      typeof taskData.projectId === 'string' &&
      typeof taskData.title === 'string' &&
      typeof taskData.description === 'string' &&
      typeof taskData.status === 'string'
    );
  }

  onSubmit() {
    const taskData = this.taskForm.value;

    if (taskData.dependsOn === '') {
      taskData.dependsOn = null;
    }

    if (!taskData.projectId || !taskData.title || !taskData.description) {
      this.errorMessage = 'Please fill in all required fields.';
      this.clearMessages();
      return;
    }

    if (this.taskForm.valid) {
      taskData.projectId = taskData.projectId.toString();

      if (this.isValidTaskData(taskData)) {
        this.taskService.createTask(taskData).subscribe(
          response => {
            this.taskForm.reset();
            this.taskForm.get('status')?.setValue('Pending');

            this.router.navigate([`/project/${taskData.projectId}`]);

            this.successMessage = 'Task successfully created!';
            this.clearMessages();
          },
          error => {
            console.error('Error while creating task.', error);
            this.errorMessage = 'Error while creating task.';
            this.clearMessages();
          }
        );
      } else {
        this.errorMessage = 'Invalid task data format.';
        this.clearMessages();
      }
    } else {
      this.errorMessage = 'Form is not valid.';
      this.clearMessages();
    }
  }

  clearMessages() {
    setTimeout(() => {
      this.successMessage = '';
      this.errorMessage = '';
    }, 3000);
  }
}

import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, NavigationEnd, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { TaskService } from '../../services/task/task.service';
import { AuthService } from '../../services/user/auth.service';
import { Subscription } from 'rxjs';


@Component({
  selector: 'app-view-members-task',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './view-members-task.component.html',
  styleUrls: ['./view-members-task.component.css']
})
export class ViewMembersTaskComponent implements OnInit {
  taskId: string | null = null;
  projectId: string | null = null;
  members: any[] = [];
  isManager: boolean = false;
  private subscription: Subscription = new Subscription();
  successMessage: string | null = null;
  errorMessage: string | null = null;


  constructor(
    private route: ActivatedRoute,
    private taskService: TaskService,
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.checkUserRole(); 
    this.listenToRouterEvents(); 


    this.projectId = this.route.snapshot.paramMap.get('projectId');
    this.taskId = this.route.snapshot.paramMap.get('taskId');
    
    console.log('Project ID:', this.projectId);
    console.log('Task ID:', this.taskId);
  
    if (this.taskId) {
      this.loadTaskMembers();
    } else {
      this.errorMessage = 'Invalid task ID';
      console.error(this.errorMessage);
    }
  }
  checkUserRole(): void {
    const role = this.authService.getUserRole();
    this.isManager = role === 'manager';
  }

  listenToRouterEvents(): void {
    this.subscription.add(
      this.router.events.subscribe((event) => {
        if (event instanceof NavigationEnd) {
          this.checkUserRole(); // Update role on route change
        }
      })
    );
  }

  loadTaskMembers(): void {
    if (this.taskId) {
      this.taskService.getTaskMembers(this.taskId).subscribe({
        next: (data) => {
          this.members = data;
        },
        error: (err) => {
          console.error('Error fetching task members:', err);
          this.errorMessage = 'Failed to fetch task members.';
        }
      });
    }
  }

  deleteMember(member: any): void {
    if (this.taskId && member.id) {
      this.taskService.removeMemberFromTask(this.taskId, member.id).subscribe({
        next: (response) => {
          this.successMessage = 'Member removed successfully!';
          this.errorMessage = null; 
          setTimeout(() => {
            this.successMessage = null; 
          }, 2000);
          this.loadTaskMembers(); 
        },
        error: (error) => {
          this.successMessage = null; 
          if (error && error.error && error.error.message) {
            this.errorMessage = error.error.message; 
          } else {
            this.errorMessage = 'Only members of completed tasks can be removed!';
          }
          setTimeout(() => {
            this.errorMessage = null; 
          }, 2000);
        }
      });
    } else {
      this.errorMessage = 'Invalid task or member';
      setTimeout(() => {
        this.errorMessage = null; 
      }, 2000);
    }
  }
  
  
  
  ngOnDestroy(): void {
    this.subscription.unsubscribe();
  }
}



import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ProjectMembersService } from '../../services/project-members/project-members.service';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-remove-members',
  standalone: true, 
  imports: [CommonModule], 
  templateUrl: './remove-members.component.html',
  styleUrls: ['./remove-members.component.css']
})
export class RemoveMembersComponent implements OnInit {
  projectId!: string;
  members: any[] = [];
  successMessage: string | null = null;
  errorMessage: string | null = null;

  constructor(
    private projectMembersService: ProjectMembersService,
    private route: ActivatedRoute
  ) {}

  ngOnInit(): void {
    this.projectId = this.route.snapshot.paramMap.get('id')!;
    this.loadMembers();
  }

  loadMembers() {
    this.projectMembersService.getProjectMembers(this.projectId).subscribe(
      (data) => {
        this.members = data;
      },
      (error) => {
        console.error('Error fetching members:', error);
        this.errorMessage = 'Error fetching members.';
      }
    );
  }

  removeMember(memberId: string) {
    this.projectMembersService.removeMember(this.projectId, memberId).subscribe(
      () => {
        this.members = this.members.filter(member => member._id !== memberId);
        this.successMessage = 'Member removed successfully!';
        setTimeout(() => {
          this.successMessage = null;
        }, 3000);
        this.loadMembers();
      },
      (error) => {
        console.error('Error removing member:', error);
        this.errorMessage = 'Cannot remove member assigned to an in-progress task.';
        setTimeout(() => {
          this.errorMessage = null;
        }, 3000);
      }
    );
  }
}

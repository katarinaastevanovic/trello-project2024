import { Component, OnInit } from '@angular/core';
import { ProjectMembersService } from '../../services/project-members/project-members.service';
import { Member } from '../../models/member/member.model';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { AuthService } from '../../services/user/auth.service';
@Component({
  selector: 'app-add-members',
  standalone: true,
  imports: [FormsModule, HttpClientModule, CommonModule],
  templateUrl: './add-members.component.html',
  styleUrls: ['./add-members.component.css']
})
export class AddMembersComponent implements OnInit {
  members: Member[] = [];
  projectMembers: Member[] = [];
  projectId: string = '';
  errorMessage: string = '';
  successMessage: string = '';
  maxMembersAllowed: number = 0;
  minMembersAllowed: number = 0;
  isManager: boolean = false;

  constructor(private projectMembersService: ProjectMembersService, private route: ActivatedRoute, private authService: AuthService) {}

  ngOnInit(): void {
    this.projectId = this.route.snapshot.paramMap.get('id') || ''; // Preuzimamo ID projekta iz parametra rute
    this.isManager = this.authService.getUserRole() === 'manager';
    if (this.isValidObjectId(this.projectId)) {
      this.fetchProjectDetails();
    } else {
      console.error('Invalid projectId format. It should be a 24-character hex string.');
    }
  }

  isValidObjectId(id: string): boolean {
    return /^[a-f\d]{24}$/i.test(id);
  }

  fetchProjectDetails() {
    this.projectMembersService.getProjectDetails(this.projectId).subscribe(
      (projectData: any) => {
        this.maxMembersAllowed = projectData.maxMembers;
        this.minMembersAllowed = projectData.minMembers;
        this.fetchProjectMembers();
      },
      (error: any) => {
        console.error('Error fetching project details:', error);
      }
    );
  }

  fetchProjectMembers() {
    this.projectMembersService.getProjectMembers(this.projectId).subscribe(
      (projectMembers: Member[]) => {
        this.projectMembers = projectMembers.map((member: any) => ({
          ...member,
          id: (member as any)._id.toString()
        }));
        this.fetchUsers();
      },
      (error: any) => {
        console.error('Error fetching project members:', error);
      }
    );
  }

  fetchUsers() {
    this.projectMembersService.getAllUsers().subscribe(
      (allUsers: Member[]) => {
        this.members = allUsers
          .filter((user: Member) => user.role === 'member') // Filtriraj samo korisnike sa rolom 'member'
          .map((user: Member) => {
            const userId = user.id.toString();
            const isSelected = this.projectMembers.some((projMember: Member) => projMember.id === userId);
            return { ...user, selected: isSelected };
          });
      },
      (error: any) => {
        console.error('Error fetching users:', error);
      }
    );
  }

  addSelectedMembers() {
    if (!this.isManager) {
      this.errorMessage = 'Only managers can add members.';
      return;
    }

    this.errorMessage = ''; // Reset error message
    
    const newMembersToAdd = this.members
      .filter((member: Member) => member.selected && !this.isMemberAlreadyAdded(member))
      .map((member: Member) => member.username);
  
    if (newMembersToAdd.length === 0) {
      this.errorMessage = 'No new members selected for addition.';
      return;
    }
  
    const currentMemberCount = this.projectMembers.length;
  
    if (currentMemberCount + newMembersToAdd.length > this.maxMembersAllowed) {
      this.errorMessage = 'You cannot add more members than the maximum allowed.';
      return;
    }
  
    if (currentMemberCount + newMembersToAdd.length < this.minMembersAllowed) {
      this.errorMessage = 'You cannot have fewer members than the minimum required.';
      return;
    }
  
    this.projectMembersService.addMembers(this.projectId, newMembersToAdd).subscribe(
      () => {
        this.errorMessage = '';
        this.successMessage = 'Members added successfully!';
        setTimeout(() => {
          this.successMessage = ''; // Automatski ukloni poruku posle 3 sekunde
        }, 3000);
        this.fetchProjectMembers();
      },
      (error: any) => {
        console.error('Error adding members:', error);
        if (error.status === 400) {
          const errorText = error.error || error.message || '';
          if (errorText.includes('the number of members cannot be less than the minimum required for the project')) {
            this.errorMessage = 'The number of members cannot be less than the minimum required for the project.';
          } else if (errorText.includes('maximum number of members reached for the project')) {
            this.errorMessage = 'The maximum number of members on the project has been reached!';
          } else {
            this.errorMessage = 'An error occurred while adding members.';
          }
        } else {
          this.errorMessage = 'An unexpected error occurred while adding members.';
        }
        setTimeout(() => {
          this.errorMessage = ''; // Automatski ukloni poruku posle 3 sekunde
        }, 3000);
      }
    );
  }

  isMemberAlreadyAdded(member: Member): boolean {
    return this.projectMembers.some((existingMember: Member) => existingMember.id === member.id);
  }
}

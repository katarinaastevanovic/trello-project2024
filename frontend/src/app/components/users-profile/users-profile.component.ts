import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/user/auth.service';
import { CommonModule } from '@angular/common'; 
import { Router, RouterModule, NavigationEnd } from '@angular/router';
import { Subscription } from 'rxjs';

export interface User {
  id?: string;
  name: string;
  lastName: string;
  username: string;
  email: string;
  password: string;
  role: string;
  isActive: boolean;
}

@Component({
  selector: 'app-users-profile',
  standalone: true,
  imports: [CommonModule, RouterModule],  
  templateUrl: './users-profile.component.html',
  styleUrls: ['./users-profile.component.css']
})
export class UsersProfileComponent implements OnInit {
  userProfile: User | null = null;
  errorMessage: string = '';
  isManager: boolean = false;
  isMember: boolean = false;
  private subscription: Subscription = new Subscription();


  constructor(private authService: AuthService, private router: Router) {}

  ngOnInit(): void {
    this.fetchUserProfile();
    this.checkUserRole(); // Provera uloge

    // Dodavanje praćenja Router Events za dinamičko osvežavanje
    this.subscription.add(
      this.router.events.subscribe((event) => {
        if (event instanceof NavigationEnd) {
          this.checkUserRole(); // Ponovo proveri ulogu nakon promene rute
        }
      })
    );
  }
  fetchUserProfile(): void {
    this.authService.getUserProfile().subscribe({
      next: (profileData) => {
        this.userProfile = profileData;  
      },
      error: (err) => {
        this.errorMessage = err;  
      }
    });
  }
  checkUserRole(): void {
    const role = this.authService.getUserRole();
    this.isManager = role === 'manager';
    this.isMember = role === 'member';
  }
  deleteAccount() {
    this.router.navigate(['/delete-account']);
  }

  changePassword() {
    this.router.navigate(['/change-password']);
  }
  ngOnDestroy(): void {
    // Oslobađanje Subscription objekata kada se komponenta uništi
    this.subscription.unsubscribe();
  }
}

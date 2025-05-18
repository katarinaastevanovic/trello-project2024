import { Component } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common'; // Dodaj CommonModule za *ngIf
import { FormsModule } from '@angular/forms';   // Dodaj FormsModule za [(ngModel)]
import { AuthService } from '../services/user/auth.service';

@Component({
  standalone: true,
  selector: 'app-reset-password',
  templateUrl: './reset-password.component.html',
  styleUrls: ['./reset-password.component.scss'],
  imports: [CommonModule, FormsModule], // Ovde dodaj CommonModule i FormsModule
})
export class ResetPasswordComponent {
  newPassword: string = '';
  confirmPassword: string = '';
  successMessage: string = '';
  errorMessage: string = '';
  token: string | null = null;

  constructor(private authService: AuthService, private route: ActivatedRoute, private router: Router) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe((params) => {
      this.token = params['token'];
      if (!this.token) {
        this.errorMessage = 'Token is missing!';
      }
    });
  }

  resetPassword(): void {
    if (this.newPassword !== this.confirmPassword) {
      this.errorMessage = 'Passwords do not match';
      return;
    }

    this.authService.resetPassword(this.token!, this.newPassword).subscribe({
      next: (response) => {
        this.successMessage = response.message || 'Password reset successfully!';
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 2000);
      },
      error: (err) => {
        const errorMessage = err.error?.message || 'An unknown error occurred';
        this.errorMessage = `Failed to reset password: ${errorMessage}`;
      },
    });
  }    
}

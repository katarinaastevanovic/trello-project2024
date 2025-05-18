import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../services/user/auth.service';
import { RecaptchaModule } from 'ng-recaptcha';

@Component({
  standalone: true,
  imports: [FormsModule, CommonModule, RecaptchaModule],
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent {
  username: string = '';
  password: string = '';
  forgotEmail: string = '';
  errorMessage: string = '';
  successMessage: string = '';
  resetMessage: string = '';
  showForgotPassword: boolean = false;
  showMagicLink: boolean = false;
  magicEmail: string = ''; 
  magicLinkMessage: string = ''; 
  captchaToken: string | null = null;

  constructor(private authService: AuthService, private router: Router, private route: ActivatedRoute) {}

  

  // Funkcija za prijavu korisnika
  onSubmit(): void {
    if (!this.username || !this.password) {
      this.errorMessage = 'Please enter both username and password';

      setTimeout(() => {
        this.errorMessage = '';
      }, 3000);
      
      return;
    }
    
    if (!this.captchaToken) {
      this.errorMessage = 'Please complete the CAPTCHA';
      return;
    }
  
    this.authService.login({ username: this.username, password: this.password, captchaToken: this.captchaToken }).subscribe({
      next: (response: any) => {
        // Sačuvaj informacije u localStorage
        localStorage.setItem('username', response.username);
        localStorage.setItem('role', response.role);
        localStorage.setItem('token', response.token);

        localStorage.removeItem('_grecaptcha');
        
  
        this.successMessage = 'Login successful!';
        setTimeout(() => {
          this.router.navigate(['/users-projects']);
        }, 2000); // Preusmeravanje nakon 2 sekunde
      },
      error: () => {
        this.errorMessage = 'Invalid username or password';
      }
    });
  }
  
  

  openForgotPassword(): void {
    if (!this.username) {
      this.errorMessage = 'Please enter your username';
      return;
    }
    this.errorMessage = '';
    this.showForgotPassword = true;
  }

  closeForgotPassword(): void {
    this.showForgotPassword = false;
    this.forgotEmail = '';
    this.resetMessage = '';
  }

  
  sendResetLink(): void {
    if (!this.forgotEmail) {
      this.resetMessage = 'Please enter a valid email';
      return;
    }

    this.authService.sendPasswordResetLink(this.username, this.forgotEmail).subscribe({
      next: () => {
        this.resetMessage = 'Reset link sent to your email!';
      },
      error: () => {
        this.resetMessage = 'Reset link sent to your email!';
      }
    });
  }


  ngOnInit(): void {
    this.route.queryParams.subscribe((params) => {
      const token = params['token'];


      if (token) {
        // Proveri token koristeći AuthService
        this.authService.verifyMagicLink(token).subscribe({
          next: (response: any) => {
            console.log('Backend response:', response);

            localStorage.setItem('token', response.token);
            localStorage.setItem('username', response.username);
            localStorage.setItem('role', response.role);
            localStorage.removeItem('_grecaptcha');


            this.successMessage = 'Login successful via Magic Link!';
            setTimeout(() => {
              if (response.role === 'manager') {
                this.router.navigate(['/users-projects']); 
              } else if (response.role === 'member') {
                this.router.navigate(['/users-projects']); 
              } else {
                this.errorMessage = 'Unknown role. Please contact support.';
                this.router.navigate(['/login']);
              }
            }, 2000);
          },
          error: () => {
            this.errorMessage = 'Invalid or expired magic link';
            localStorage.removeItem('_grecaptcha');
          }
        });
      } 
    });
  }

  openMagicLink(): void {
    if (!this.username) {
      this.errorMessage = 'Please enter your username';
      return;
    }
    this.errorMessage = '';
    this.showMagicLink = true;
  }

  sendMagicLink(): void {
    if (!this.magicEmail) {
      this.magicLinkMessage = 'Please enter a valid email';
      return;
    }

    this.authService.sendMagicLink(this.username, this.magicEmail).subscribe({
      next: () => {
        this.magicLinkMessage = 'Magic link sent to your email!';
        setTimeout(() => {
          this.magicLinkMessage = '';
          this.showMagicLink = false;
        }, 3000);
      },
      error: () => {
        this.magicLinkMessage = 'Magic link sent to your email!';
      }
    });
  }

   // Čuvanje CAPTCHA tokena
   onCaptchaResolved(token: string | null): void {
    console.log('CAPTCHA resolved with token:', token);
    this.captchaToken = token; 
  }

  openRegister() {
    this.router.navigate(['/register']);
  }
}
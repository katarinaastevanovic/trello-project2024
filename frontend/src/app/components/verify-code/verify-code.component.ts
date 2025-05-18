import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import {  Router } from '@angular/router';


@Component({
  selector: 'app-verify-code',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, HttpClientModule],
  templateUrl: './verify-code.component.html',
  styleUrls: ['./verify-code.component.css']
})
export class VerifyCodeComponent implements OnInit {
  verifyCodeForm: FormGroup;
  username: string = '';
  successMessage: string | null = null;
  errorMessage: string | null = null;

  constructor(private fb: FormBuilder, private http: HttpClient, private router: Router) {
    this.verifyCodeForm = this.fb.group({
      code: ['', [Validators.required, Validators.minLength(6), Validators.maxLength(6)]]
    });
  }

  ngOnInit(): void {
    this.username = localStorage.getItem('username') || '';
  }

  onSubmit() {
    if (this.verifyCodeForm.valid) {
       // Priprema podataka za slanje, uključujući username iz localStorage i kod iz forme
      const data = {
        username: this.username,
        code: this.verifyCodeForm.value.code
      };

      this.http.post(`http://localhost:8000/api/users/verify-code`, data, { responseType: 'text' }).subscribe({
        next: (response) => {
          console.log('Response from server:', response);
          this.successMessage = 'Verification successful. You can now log in.';
          this.errorMessage = null; 
          localStorage.removeItem('username');
          this.verifyCodeForm.reset();
          setTimeout(() => {
            this.successMessage = null; 
            this.router.navigate(['/login']);
          }, 2000);
        },
        error: (error) => {
          console.error('Error during verification:', error);
          this.successMessage = null; 
          if (error.status === 400) {
            this.errorMessage = 'Bad request. Please make sure all data is correct.';
          } else if (error.status === 401) {
            this.errorMessage = 'Username mismatch or invalid code. Please try again.';
          } else if (error.status === 404) {
            this.errorMessage = 'User not found. Please check the username.';
          } else {
            this.errorMessage = 'Verification failed. Please try again.';
          }
          setTimeout(() => {
            this.errorMessage = null; 
          }, 2000);
        },
      });
    } else {
      this.errorMessage = 'Please fill out the form correctly.';
      setTimeout(() => {
        this.errorMessage = null; 
      }, 2000);
    }
  }
}

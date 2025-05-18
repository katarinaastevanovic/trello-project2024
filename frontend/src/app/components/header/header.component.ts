import { Component, OnInit } from '@angular/core';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { AuthService } from '../../services/user/auth.service';
import { CommonModule } from '@angular/common';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [RouterModule, CommonModule],
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css'], // Pazite na "styleUrls", sada je ispravno!
})
export class HeaderComponent implements OnInit {
  isManager: boolean = false;
  isMember: boolean = false;
  isAuthenticated: boolean = false;
  private subscription: Subscription = new Subscription();

  constructor(private router: Router, private authService: AuthService) {}

  ngOnInit(): void {
    this.checkUserStatus();
    this.subscription.add(
      this.router.events.subscribe((event) => {
        if (event instanceof NavigationEnd) {
          this.checkUserStatus();
        }
      })
    );
  }

  checkUserStatus(): void {
    const role = this.authService.getUserRole();
    this.isAuthenticated = !!role; // Proverava da li postoji neka uloga
    this.isManager = role === 'manager';
    this.isMember = role === 'member';
  }

  logout(): void {
    localStorage.clear();
    this.router.navigate(['/login']);
  }
}

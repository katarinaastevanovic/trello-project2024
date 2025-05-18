import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, Router } from '@angular/router';
import { AuthService } from '../services/user/auth.service';


@Injectable({
  providedIn: 'root',
})
export class RoleGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

 canActivate(route: ActivatedRouteSnapshot): boolean {
    const requiredRoles = route.data['roles'] as string[];
    if (this.authService.isAuthorized(requiredRoles)) {
      return true;
    } else {
      alert('You do not have the required role to access this page.');
      return false; // Sprečava aktivaciju rute
    }
  }
}

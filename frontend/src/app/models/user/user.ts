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
  
  export interface LoginRequest {
    username: string;
    password: string;
    captchaToken: string | null;
  }
  
  export interface LoginResponse {
    token: string;
    username: string;
    role: string;
  }
  
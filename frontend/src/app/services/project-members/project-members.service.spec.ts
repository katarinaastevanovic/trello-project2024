import { TestBed } from '@angular/core/testing';

import { ProjectMembersService } from './project-members.service';

describe('ProjectMembersService', () => {
  let service: ProjectMembersService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(ProjectMembersService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});

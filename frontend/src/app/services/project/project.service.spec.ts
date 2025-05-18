import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';

import { ProjectService } from './project.service';

describe('ProjectService', () => {
  let service: ProjectService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [ProjectService]
    });
    service = TestBed.inject(ProjectService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify(); // Proverava da nema nepotvrđenih HTTP zahteva
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should create a new project', () => {
    const dummyProject = {
      name: 'Project Alpha',
      expectedEndDate: '2024-12-31T00:00:00Z',
      minMembers: 3,
      maxMembers: 10
    };

    service.createProject(dummyProject).subscribe((response) => {
      expect(response).toEqual(dummyProject);
    });

    const req = httpMock.expectOne(service['apiUrl']);
    expect(req.request.method).toBe('POST');
    req.flush(dummyProject); // Simulira odgovor sa servera
  });
});
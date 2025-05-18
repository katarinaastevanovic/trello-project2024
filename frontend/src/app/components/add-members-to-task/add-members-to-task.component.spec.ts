import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AddMembersToTaskComponent } from './add-members-to-task.component';

describe('AddMembersToTaskComponent', () => {
  let component: AddMembersToTaskComponent;
  let fixture: ComponentFixture<AddMembersToTaskComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AddMembersToTaskComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(AddMembersToTaskComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

import { ComponentFixture, TestBed } from '@angular/core/testing';

import { VerifyCodeComponentComponent } from './verify-code.component';

describe('VerifyCodeComponentComponent', () => {
  let component: VerifyCodeComponentComponent;
  let fixture: ComponentFixture<VerifyCodeComponentComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [VerifyCodeComponentComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(VerifyCodeComponentComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

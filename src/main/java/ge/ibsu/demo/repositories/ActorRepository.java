package ge.ibsu.demo.repositories;
import ge.ibsu.demo.entities.Actor;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ActorRepository extends JpaRepository<Actor, Long> {
}

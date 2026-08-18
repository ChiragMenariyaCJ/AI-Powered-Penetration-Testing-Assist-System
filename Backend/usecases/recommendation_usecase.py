from fastapi import HTTPException, status

from Backend.repositories.vulnerability_repository import VulnerabilityRepository
from Backend.repositories.recommendation_repository import RecommendationRepository
from Backend.services.ai_recommendation_engine import AIRecommendationEngine


class RecommendationUseCase:

    def __init__(
        self,
        recommendation_repository: RecommendationRepository,
        vulnerability_repository: VulnerabilityRepository,
    ):
        self.recommendation_repository = recommendation_repository
        self.vulnerability_repository = vulnerability_repository
        self.ai_engine = AIRecommendationEngine()

    def generate_recommendations_for_vulnerability(
        self, vulnerability_id: int
    ) -> dict:
        """
        Generate AI recommendations for a vulnerability
        
        Args:
            vulnerability_id: ID of vulnerability to analyze
            
        Returns:
            Dict with generated recommendations
        """
        vulnerability = (
            self.vulnerability_repository.get_vulnerability_by_id(vulnerability_id)
        )

        if not vulnerability:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found",
            )

        # Prepare vulnerability data for AI engine
        vuln_data = {
            "host": vulnerability.host,
            "port": vulnerability.port,
            "service": vulnerability.service,
            "severity": vulnerability.severity,
            "vulnerability_type": vulnerability.vulnerability_type,
            "description": vulnerability.description,
        }

        # Generate recommendations
        ai_recommendations = self.ai_engine.generate_recommendations(vuln_data)

        # Store recommendations in database
        created_recommendations = []
        for ai_rec in ai_recommendations:
            rec = self.recommendation_repository.create_recommendation(
                vulnerability_id=vulnerability_id,
                attack_technique=ai_rec["attack_technique"],
                mitre_technique_id=ai_rec.get("mitre_technique_id"),
                exploitation_method=ai_rec["exploitation_method"],
                risk_level=ai_rec["risk_level"],
                priority=ai_rec["priority"],
                likelihood=ai_rec["likelihood"],
                impact=ai_rec["impact"],
                prerequisites=ai_rec.get("prerequisites"),
                tools_required=ai_rec.get("tools_required"),
                execution_steps=ai_rec.get("execution_steps"),
                post_exploitation=ai_rec.get("post_exploitation"),
                confidence_score=ai_rec["confidence_score"],
            )
            created_recommendations.append(rec)

        return {
            "vulnerability_id": vulnerability_id,
            "recommendations_count": len(created_recommendations),
            "recommendations": created_recommendations,
        }

    def get_recommendation_by_id(self, recommendation_id: int):
        recommendation = (
            self.recommendation_repository.get_recommendation_by_id(recommendation_id)
        )

        if not recommendation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recommendation not found",
            )

        return recommendation

    def get_all_recommendations(self, vulnerability_id: int | None = None):
        if vulnerability_id is not None:
            vulnerability = (
                self.vulnerability_repository.get_vulnerability_by_id(
                    vulnerability_id
                )
            )

            if not vulnerability:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Vulnerability not found",
                )

            recommendations = (
                self.recommendation_repository.get_recommendations_by_vulnerability_id(
                    vulnerability_id
                )
            )
        else:
            recommendations = (
                self.recommendation_repository.get_all_recommendations()
            )

        return {
            "count": len(recommendations),
            "recommendations": recommendations,
        }

    def update_recommendation(self, recommendation_id: int, request):
        recommendation = (
            self.recommendation_repository.get_recommendation_by_id(
                recommendation_id
            )
        )

        if not recommendation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recommendation not found",
            )

        update_data = request.model_dump(exclude_unset=True)

        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields provided for update",
            )

        return self.recommendation_repository.update_recommendation(
            recommendation,
            update_data,
        )

    def delete_recommendation(self, recommendation_id: int):
        recommendation = (
            self.recommendation_repository.get_recommendation_by_id(
                recommendation_id
            )
        )

        if not recommendation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recommendation not found",
            )

        deleted_rec = {
            "id": recommendation.id,
            "vulnerability_id": recommendation.vulnerability_id,
            "attack_technique": recommendation.attack_technique,
        }

        self.recommendation_repository.delete_recommendation(recommendation)

        return {
            "message": "Recommendation deleted successfully",
            "recommendation": deleted_rec,
        }

    def approve_recommendation(self, recommendation_id: int, approved_by: str):
        recommendation = (
            self.recommendation_repository.get_recommendation_by_id(
                recommendation_id
            )
        )

        if not recommendation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recommendation not found",
            )

        return self.recommendation_repository.approve_recommendation(
            recommendation, approved_by
        )

    def reject_recommendation(self, recommendation_id: int):
        recommendation = (
            self.recommendation_repository.get_recommendation_by_id(
                recommendation_id
            )
        )

        if not recommendation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recommendation not found",
            )

        return self.recommendation_repository.reject_recommendation(recommendation)

    def get_recommendations_by_status(self, status_filter: str):
        valid_statuses = [
            "PENDING_APPROVAL",
            "APPROVED",
            "REJECTED",
            "EXECUTED",
        ]
        if status_filter not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
            )

        recommendations = (
            self.recommendation_repository.get_recommendations_by_status(
                status_filter
            )
        )

        return {
            "count": len(recommendations),
            "status": status_filter,
            "recommendations": recommendations,
        }

    def get_attack_score(self, vulnerability_id: int) -> dict:
        """Calculate attack score for a vulnerability"""
        vulnerability = (
            self.vulnerability_repository.get_vulnerability_by_id(vulnerability_id)
        )

        if not vulnerability:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found",
            )

        vuln_data = {
            "host": vulnerability.host,
            "port": vulnerability.port,
            "service": vulnerability.service,
            "severity": vulnerability.severity,
        }

        return self.ai_engine.calculate_attack_score(vuln_data)
